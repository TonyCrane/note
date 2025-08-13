---
counter: True
comment: True
---

# KVM 虚拟机基本用法

!!! abstract
    在 Linux 上利用 KVM 虚拟化技术来创建和管理虚拟机，记录一些基本的用法

## 安装

忘记本地怎么安装的了，反正通过 apt 就可以直接装：

```shell
apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virtinst libvirt-daemon
```

使用 cockpit 的话可以装 cockpit-machines 来在 cockpit 网页上管理 KVM 虚拟机：

```shell
apt install cockpit-machines
```

## 使用
### Cockpit

直接在页面上点点点就好了，基本都很直接。

虚拟机启动后 cockpit 会提供 VNC 控制台界面，可以直接在 cockpit 里操作图形界面。

### 命令与 xml 文件

#### 虚拟机相关

利用 virsh 命令来管理 KVM 虚拟机（root 用户）：

```shell
virsh list --all        # 列出所有虚拟机
virsh start <vm_name>   # 启动虚拟机
virsh destroy <vm_name> # 关闭虚拟机
virsh edit <vm_name>    # 编辑虚拟机配置
```

添加 disk，在 edit 的 xml 文件中 devices 部分添加：

```xml
<disk type='file' device='cdrom'>
  <driver name='qemu' type='raw'/>
  <source file='/path/to/image.iso'/>
  <target dev='hdb' bus='ide'/>
  <readonly/>
  <address type='drive' controller='0' bus='0' target='0' unit='0'/>
</disk>
```

其中 target 的 dev 要不能冲突，address 部分的 bus 和 unit 也要避免冲突，且一个 bus 上只能有两个 unit。

启动方式可以在 `#!xml <os>` 部分的 `#!xml <boot>` 中修改，`#!xml dev='hd'` 为从硬盘启动，`#!xml dev='cdrom'` 为从光盘启动。

#### 存储卷相关

除了以文件形式添加 disk 以外，还可以通过 kvm 的存储池/存储卷来添加，可以通过 cockpit 界面来创建，也可以通过命令：

```shell
# 创建存储池，存储在 /path/to/pool 目录下
virsh pool-define-as <pool-name> --type dir --target /path/to/pool
virsh pool-start <pool-name>        # 启动存储池
virsh pool-autostart <pool-name>    # 自动启动存储池
# 创建存储卷，存放在池的目录下，以 vol-filename 命名，最大 200G
virsh vol-create-as --pool <pool-name> --name <vol-filename> --capacity 200G --allocation 100G --format raw
virsh vol-info <vol-filename> <pool-name>   # 查看卷信息
virsh vol-list <pool-name>                  # 列出池中的卷
```

其中可以有两种格式，以 .img 结尾的 raw 格式，和以 .qcow2 结尾的 qcow2 格式。创建卷后，可以在 xml 中引用这些卷：

```xml
<disk type='volume' device='disk'>
  <driver name='qemu' type='raw' discard='unmap'/>
  <source pool='<pool-name>' volume='<vol-filename>'/>
  <target dev='sda' bus='ide'/>
  <address type='drive' controller='0' bus='0' target='0' unit='1'/>
</disk>
```

同样需要注意 target 和 address 不要冲突。

#### VNC 相关

cockpit 创建的默认配置貌似只能在 cockpit 中打开 vnc 控制台使用，想要在外部使用 vnc 客户端可能需要自己设置密码才行，在 edit 的 xml 文件中，修改：

```xml
<graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1' passwd='<password>'>
  <listen type='address' address='127.0.0.1'/>
</graphics>
```

可以通过 `#!shell virsh vncdisplay <vm_name>` 来查看 vnc 端口，端口号的结果加上 5900 是实际的 TCP 端口号，例如 `127.0.0.1:0` 需要通过 5900 端口来连接。可以通过 ssh 来转发出端口：

```shell
ssh -N -L 5900:127.0.0.1:5900 user@remote-host
```

然后在浏览器打开 `vnc://localhost:5900` 即可跳转客户端进行连接，mac 可通过系统自带的屏幕共享 app 来进行连接，需要输入 xml 中指定的密码。

或者也可以将 xml 中监听的 ip 改为 0.0.0.0 然后防火墙开放出端口来直接连接。

## 其他问题

### kvm 权限问题

如果运行虚拟机时报错类似 cannot access storage file (as uid:xxx, gid:xxx) permission denied，显示访问 disk 的文件时出现了权限问题，可以修改 /etc/libvirt/qemu.conf，在末尾添加：

```conf
user = "root"
group = "root"
```

然后 `systemctl restart libvirtd.service` 重启服务，再启动虚拟机即可。

### qemu 与 volume 权限问题

如果使用存储池/存储卷来创建 disk 的话，启动的时候可能会遇到另一个权限问题：

```text
error: internal error: process exited while connecting to monitor:
qemu-system-x86_64: -blockdev ...: Could not open '/path/to/volume': Permission denied
```

解决方式一种是弃用 volume 方式，改成文件方式载入 disk，另一种是关闭 apparmo，在 /etc/libvirt/qemu.conf 中添加：

```conf
security_driver = "none"
```

然后 `systemctl restart libvirtd.service` 重启服务，再启动虚拟机即可。

### NAT 网络端口转发

虚拟机默认使用 NAT 网络模式，要想从外部访问虚拟机的端口，需要通过 iptables 进行端口转发。首先需要修改 /etc/sysctl.conf：

```conf
net.ipv4.ip_forward=1
```

然后 `sysctl -p` 修改来支持 IPv4 上的流量转发，然后通过 iptables 来转发端口：

```shell
# 将外部访问宿主机 host_port 的流量转发到 kvm_ip:kvm_port
iptables -t nat -A PREROUTING -p tcp --dport <host_port> -j DNAT --to-destination <kvm_ip>:<kvm_port>
# 将目标为 kvm_ip:kvm_port 的数据包的源地址修改为 host_ip
iptables -t nat -A POSTROUTING -p tcp -d <kvm_ip> --dport <kvm_port> -j SNAT --to-source <host_ip>
# 查看 iptables
iptables -t nat -nL --line-numbers
```

其中 kvm_ip 和 host_ip 都是在 KVM NAT 网卡上的 IP 地址，默认应该为 `192.168.xxx.xxx`。

### 救援模式

可以通过加载额外 iso 镜像进入救援模式并挂载虚拟机磁盘的方式来修改虚拟机的系统文件，来修复意外造成的虚拟机无法启动，或绕过特定镜像平台的登录限制（如 GitHub Enterprise）。

首先需要一个 Linux 的 iso 安装镜像，版本无所谓，然后通过 edit xml 的方式将镜像作为 cdrom 并设置从 cdrom 启动：

```xml
<os>
  <type arch='x86_64' machine='pc-i400fx-10.0'>hvm</type>
  <boot dev='cdrom'/>
  <bootmenu enable='yes'/>
</os>
<devices>
  <emulator>/usr/bin/qemu-system-x86_64</emulator>
  <disk type='file' device='disk'>
    <driver name='qemu' type='qcow2'/>
    <source file='/path/to/disk.qcow2'/>
    <target dev='hda' bus='ide'/>
    <address type='drive' controller='0' bus='0' target='0' unit='0'/>
  </disk>
  <disk type='file' device='cdrom'>
    <driver name='qemu' type='raw'/>
    <source file='/path/to/image.iso'/>
    <target dev='hdb' bus='ide'/>
    <address type='drive' controller='0' bus='0' target='0' unit='1'/>
  </disk>
```

然后启动虚拟机进入安装 Linux 的界面，选择进入 Rescue Mode，会准备一个基本环境，并选择挂载原来的系统盘。进入系统后就可以修改原来系统盘中的所有文件。例如：

- 修改 root 密码
    - 在 /etc/shadow 文件中找到 root 一行，修改第一个 : 和第二个 : 中间的内容为 `#!shell openssl passwd -1 "<new_password>"` 的结果
- 允许 root 登录
    - 在 /etc/passwd 文件中找到 root 一行，修改 /usr/sbin/nologin 为 /bin/bash
- 允许 ssh 从密码登录以及允许 root 登录
    - 修改 /etc/ssh/sshd_config 文件：
        ```config
        PermitRootLogin yes
        PasswordAuthentication yes
        ```


## Reference

- https://blog.csdn.net/yuezhilangniao/article/details/113743688
- https://zhensheng.im/2019/02/06/qemu-with-pool-volume-storage-could-not-open-xxxxxxx-permission-denied.meow
- https://www.cnblogs.com/sky-cheng/p/16087283.html
- https://blog.csdn.net/weixin_47680367/article/details/126183181
- https://developer.aliyun.com/article/1361666
- https://blog.csdn.net/qq_34777982/article/details/125396150
- https://blog.rabit.pw/2022/github-enterprise-reverse-engineering/
