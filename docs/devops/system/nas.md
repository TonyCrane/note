---
counter: True
comment: True
---

# NAS 配置记录

!!! abstract
    在自组 NAS 和维护时进行的一些配置记录

    后补的记录，所以并非搭建 NAS 的全过程，慢慢来补，目前只有少部分
    
    搭建 NAS 的时候参考了非常多：<https://blog.dawnocean.site/NAS-Router-0>

## 拆分出去的页面

一些并非 NAS 特定使用的配置划分到了其他页面中：

- [podman 配置](docker.md#podman)
- [网络基础配置](../network/basic.md)：利用 nmtui 来配置内网静态 ip，利用 ethtool 修改网卡速率
- [Clash 配置](../network/clash.md#gui_1)：在服务器上配置代理程序和控制页面
- [内网穿透与反向代理](../network/tunnel.md)：搭建的 NAS 可用于穿透内网
- [Caddy HTTP 服务器](../network/server.md#caddy)：利用 Caddy 进行服务的反向代理，实现域名访问和自签署 SSL 证书

## SMB 与备份配置

SMB (Server Message Block) 是微软的在计算机间共享文件、设备等的协议。Samba 是 Linux 上的一个 SMB 实现，可以进行文件的共享，并在客户端上挂载共享目录。同时也可以作为 macOS 时间机器的备份磁盘，实现定期网络备份。

```shell
apt install samba
```

服务通过 smb.service systemd 服务来管理，配置文件在 /etc/samba/smb.conf，一些常用的配置和为了让 mac 时间机器能使用的配置如下：

```conf
[global]
   smb ports = ...
### Time Machine Compatibility ###
   min protocol = SMB2
   server min protocol = SMB2
   vfs objects = catia fruit streams_xattr
   fruit:nfs_aces = no
   fruit:metadata = stream
   fruit:model = MacSamba
   fruit:posix_rename = yes
   fruit:veto_appledouble = no
   fruit:wipe_intentionally_left_blank_rfork = yes
   fruit:delete_empty_adfiles = yes

   wins support = yes
   dns proxy = yes

   include = registry

[<storage-name>]
  comment = ...
  public = no
  path = /path/to/storage
  read only = no
  valid users = ...
  force user = ...
  force group = ...

[mac-backup]
  comment = MacBook TimeMachine Backup
  path = /path/to/mac-backup
  public = no
  read only = no
  fruit:time machine = yes
  fruit:aapl = yes
  valid users = ...
  force user = ...
  force group = ...
```

同时需要通过 `smbpasswd -a <username>` 来为用户设置 smb 登录用的密码。以及还要注意存储路径的 owner 和权限问题。

虽然 cockpit 有 45Drive's File Sharing 插件可以管理 samba 配置，但用起来不如自己手动改配置。

macOS 上挂载目录可以直接在访达 > 前往 > 连接服务器…中输入 `smb://<ip>:<port>` 来连接，输入配置的用户名和 smb 登录密码，然后选择需要挂载的存储目录。

### 时间机器备份问题

在修改过 smb 端口后，即使为时间机器专门添加了设置，在备份的时候也会出现连不上磁盘的情况。

这是因为在进行时间机器备份的时候 macOS 会使用系统内记录的用户和密码来登录备份用的目录，但系统内保存的 smb 地址中并不包含端口号信息，所以在备份时实际在登录的是 smb 默认端口号的服务。为了自定义端口号能够顺利登录，需要手动修改记录的密钥信息。

打开“钥匙串访问” app（不是新的“密码” app），在登录-所有密码中搜索地址或域名，找到“网络密码”和“时间机器网络密码”两项，双击打开，修改其中的“位置”，手动加上端口号，即可在后续自动登录上备份磁盘。

## ZFS 相关

目前用的是 ZFS 的 RAID-1，两块机械硬盘互相备份。

### 调盘修复

经历过一次断电导致的磁盘损坏，zpool status 可以看到状态为 DEGRADED，其中坏掉的硬盘状态为 REMOVED。

修复过程：

1. 关机，拔掉坏掉的硬盘（可以留下一个然后启动来确认哪个盘坏了）
    - 可以都拔掉，然后等新磁盘到货后再一起装上
    - 可以 `zpool export <pool-name>` 来卸载池（但好像经过重启用不用这句也无所谓）
2. 装上新硬盘，启动
3. 用 `zpool offline <pool_name> <bad_device>` 把坏掉的盘下线
    - 其中 `<bad_device>` 是 zpool status 里 config 显示的设备名字
4. 用 `zpool replace <pool_name> <bad_device> <new_device>` 把新盘替换进来
    - 其中 `<new_device>` 是新磁盘的地址，即 `/dev/sdX` 之类，可以通过 lsblk 来确认
    - 如果新磁盘没格式化，可以在命令后面加上 `-f`
5. 用 `zpool status` 查看恢复进度，等待 resilvering 完成后会自动上线
    - 期间现有的 DEGRADED pool 也可以正常使用

### 更换磁盘名称

前面这一步修复中存在问题，就是用了 `/dev/sdX` 这样的名称来指定磁盘，但这种名称是会变的，比如重启后可能就变成了 `/dev/sdY` 了，导致 zpool status 出现 DEGRADED，其中这个磁盘状态显示为 FAULTED，且后面会显示 was /dev/sdX。所以最好用 /dev/disk/by-id/ 下的名称来指定磁盘。修改过程：

1. 停止当前 scrub：`sudo zpool scrub -s <pool_name>`
2. 导出 pool（卸载）：`sudo zpool export <pool_name>`（或者加 -f）
3. 用新路径重新导入：`sudo zpool import -d /dev/disk/by-id <pool_name>`
4. 用 `zpool status -P` 确认状态正常且路径已经修改正确
    - 这里的 status/action 可能会说有 unrecoverable error，而且改了名的盘可能 CKSUM 会有计数
    - 可以通过 `sudo zpool clear <pool_name>` 来清除错误计数
    - 然后补跑一次 scrub：`sudo zpool scrub <pool_name>`

!!! llm "来自 GPT 5.2"
    什么时候才需要再 zpool replace：

    - 只有当 export/import -d /dev/disk/by-id 后，zpool status -P 仍然显示 /dev/sdX，或者某个 vdev 仍然 FAULTED/UNAVAIL，才考虑再用 zpool replace 把旧路径替换为 by-id。

    只有在下面情况才建议 zpool replace（或进一步查硬件）：

    - zpool status 里 CKSUM/READ/WRITE 计数在持续增加（清零后又涨）
    - scrub 报修复/无法修复错误
    - dmesg 里有大量 SATA 重置、I/O error（更像线材/供电/接口问题）

## UPS 相关

将 UPS 的线缆连到主机后用 apcupsd 来管理 APC UPS：

```shell
sudo apt install apcupsd apcupsd-cgi
```

配置文件在 /etc/apcupsd/apcupsd.conf，主要配置项如下：

```conf
UPSNAME xxx
UPSCABLE usb
UPSTYPE usb
DEVICE          # 留空来自动检测

BATTERYLEVEL 5  # 剩余电量小于等于 5% 时自动关机
MINUTES 3       # 剩余时间小于等于 3 分钟时自动关机
TIMEOUT 0       # 断电后多少秒后自动关机，0 表示不启用
```

修改配置后还需要修改 /etc/default/apcupsd，将 `ISCONFIGURED` 设为 `yes`，然后重启 apcupsd 服务并启用开机自启：

```shell
sudo systemctl enable apcupsd
sudo systemctl restart apcupsd
sudo apcaccess status  # 检查状态
```

安装了 apcupsd-cgi 后可以通过 webUI 查看 UPS 状态，cgi 脚本地址在 /usr/lib/cgi-bin/apcupsd/ 目录下，可以通过 web 服务器来配置 cgi，例如带有 cgi 插件的 Caddy 可以配置：

```nginx
cgi / /usr/lib/cgi-bin/apcupsd/multimon.cgi
cgi /upsfstats.cgi* /usr/lib/cgi-bin/apcupsd/upsfstats.cgi {
    script_name /upsfstats.cgi
}
cgi /upsimage.cgi* /usr/lib/cgi-bin/apcupsd/upsimage.cgi {
    script_name /upsimage.cgi
}
cgi /upsstats.cgi* /usr/lib/cgi-bin/apcupsd/upsstats.cgi {
    script_name /upsstats.cgi
}
```

## 自建 Gitea 相关

通过 rootful podman compose 来搭建的 Gitea 服务。

### 配置 SSH 访问

参考 [Gitea 官方文档](https://docs.gitea.com/zh-cn/installation/install-with-docker#ssh-%E5%AE%B9%E5%99%A8%E7%9B%B4%E9%80%9A)

首先要在宿主机上创建 git user (e.g. 1001:1001)，然后为主机 git 用户生成密钥对：

```shell
sudo -u git ssh-keygen -t rsa -b 4096 -C "Gitea Host Key"
```

之后需要向 /usr/local/bin/gitea 写入以下内容并赋予执行权限（chmod +x /usr/local/bin/gitea）：

```shell
ssh -p 2222 -o StrictHostKeyChecking=no git@127.0.0.1 "SSH_ORIGINAL_COMMAND=\"$SSH_ORIGINAL_COMMAND\" $0 $@"
```

还需要将 git 用户的公钥添加进 git 用户自己的 authorized_keys 中：

```shell
echo "$(cat /home/git/.ssh/id_rsa.pub)" >> /home/git/.ssh/authorized_keys
```

然后对于容器：

```yaml
environment:
  - USER_UID=1001
  - USER_GID=1001
volumes:
  - /home/git/.ssh/:/data/git/.ssh
ports:
  - "127.0.0.1:2222:22" # 与 /user/local/bin/gitea 中的端口同步
```

再启动即可通过 ssh 的方式访问 repo 了。如果宿主机的 SSH 端口不在 22 的话需要修改 gitea/gitea/conf/app.ini 中 \[server\] 部分的 SSH_PORT，这样在网页中复制 SSH 地址时才会正确。

### Gitea Action Runner 配置

参考 [Gitea 官方文档](https://docs.gitea.com/zh-cn/usage/actions/act-runner#%E4%BD%BF%E7%94%A8-docker-compose-%E8%BF%90%E8%A1%8C-runner)

这里打算在同一个 podman compose 里面运行 runner 容器，然后将宿主机中 git 用户的 podman socket 映射进容器中的 docker socket 来在 rootless podman 容器中运行 job。

podman 和 docker 的 socket 是兼容的，podman 比较特殊的是 rootless 的部分每个用户会有一个自己的 socket，而且默认情况下 systemd 不保留用户 service，在用户退出登陆后会停用 unit，所以需要为 git 用户配置 linger：

```shell
sudo loginctl enable-linger git
```

然后需要手动为 git 用户激活 socket，参考 [podman docs](https://github.com/containers/podman/blob/main/docs/tutorials/socket_activation.md#socket-activation-of-the-api-service)：

```shell
systemctl --user start podman.socket
ls $XDG_RUNTIME_DIR/podman/podman.sock
```

这样这个 socket 就会保存在 /run/user/1001/podman/podman.sock 中，但如果直接 sudo su git 进入 git 用户的话运行 systemctl --user 会报错：

```text
Failed to connect to user scope bus via local transport: $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined
```

因为这样进行的登陆不会初始化这两个环境变量，既然前面已经将 git 自己的公钥添加进 authorized_keys 了，那么可以通过 git 用户 ssh git@127.0.0.1 来再次进入 git 用户的 shell，这时就会经过一个登陆过程，然后再运行 systemctl --user start podman.socket 就不会报错了。

然后在 compose 文件中加入一个 service 来运行 runner：

```yaml
  runner0:
    image: gitea/act_runner:latest
    restart: always
    user: 0:0
    uidmap: 0:1000:10
    gidmap: 0:1000:10
    environment:
      CONFIG_FILE: /config.yaml
      GITEA_INSTANCE_URL: "<url>"
      GITEA_RUNNER_REGISTRATION_TOKEN: "<token>"
      GITEA_RUNNER_NAME: "runner0"
    volumes:
      - ./runner0/config.yaml:/config.yaml
      - ./runner0/data:/data
      - /run/user/1001/podman/podman.sock:/var/run/docker.sock
    depends_on:
      - server
```

token 为在 Gitea 网页端生成的 runner 注册 token，默认的 config 通过以下命令获取：

```shell
sudo podman run --entrypoint="" --rm -it docker.io/gitea/act_runner:latest act_runner generate-config > config.yaml
```

它可以运行的环境（即 workflow 文件中可以配置的 runs-on 环境）在 config.yaml 中的 runner.labels 部分配置，格式为 `<labels>:docker://<image>`，自带了 ubuntu-latest, ubuntu-22.04, ubuntu-20.04 三个环境，可以添加自定义环境比如 `debian-13:docker://docker.io/node:25-trixie` 之类的。

运行后可以正常注册 runner，但运行测试 job 的时候会有问题，网页端运行 setup 的时候包含报错：

```text
failed to create container: 'Error response from daemon: make cli opts(): making volume mountpoint for volume /var/run/docker.sock: mkdir /var/run/docker.sock: permission denied'
```

搜到了相关 issue [gitea/act_runner#223](https://gitea.com/gitea/act_runner/issues/223)，下面评论的解决办法是修改 config 文件，将其中的 container.docker_host 改为 "-"，这样 runner 会使用宿主机的 docker socket，即 podman socket，从而避免权限问题。

接下来的问题是运行到 checkout 步骤的时候会 Could not connect to server，也就是说 job runner 容器中无法连接到主机中的服务，本来以为是防火墙的问题，但关掉也会这样。搜起来是因为 rootless podman 的网络隔离导致的，rootless 会使用 pasta 来配置网络，而非 rootful podman 的 bridge 网络，导致容器解析到的主机地址其实指向容器内部网络而非宿主机网络。

一个解决方案是在 job container 创建时添加额外的 host 将宿主机的域名解析到 host-gateway 上，这样容器内访问宿主机域名的服务就能确保真的是访问宿主机而非容器内网络了。需要修改 runner0/config.yaml 中的 container.options：

```yaml
container:
  options: "--add-host=<hostname>:host-gateway"
```

然后就可以正常使用了。虽然感觉这个解决方法并不优雅，但感觉 rootless podman 的网络部分确实是晦涩难懂，目前没精力再深入研究了。其实还试过用回 pasta 之前的 slirp4netns 作为 rootless 的网络应用，实测可以访问到宿主机服务：

```shell
podman run -it --network slirp4netns docker.gitea.com/runner-images:ubuntu-latest bash
```

但在 config 中将 container.network 改为 slirp4netns 后会报错：networks and static ip/mac address can only be used with Bridge mode networking，搜了下看不懂怎么解决，就没再研究了。

## Trouble Shooting

### 启动引导无法加载系统盘

通过 grub 进入系统后，出现报错：

```text
mdadm: No arrays found in config gile or automatically
mdadm: No arrays found in config gile or automatically
...
mdadm: error opening /dev/md?*: No such file or directory
...
Gave up waiting for root file system device.
...
ALERT!  UUID=<uuid> does not exist.  Dropping to a shell!
```

然后进入了 initramfs shell，在 shell 中 fdisk -l 看不到系统盘，/dev/ 下也没有这个设备，说明系统盘没有被识别到或者炸了。通过 PE 盘进入 Windows 然后用 DiskGenius 检查，可以发现这块系统盘仍然可以正常读取，且分区表正常，而且 uuid 和启动中未找到的 uuid 一致。

!!! llm "来自 GPT 5.2"
    你描述的现象（initramfs 里只看到两块机械盘、系统 SSD 完全不枚举；但用 PE/Windows 工具能正常看到 SSD 和 ext4）高度像是 Linux 在早期启动阶段没能驱动你的存储控制器，最常见原因是 BIOS/UEFI 把磁盘控制器模式切到了 Intel RST/RAID/VMD（Windows/PE 仍能识别，Linux 需要 vmd/相应模块，否则 NVMe/SSD 在 initramfs 里直接“消失”），从而导致 root=UUID=... 找不到，进而 Gave up waiting for root file system device。

    ……

    完全没有 /dev/nvme0n1 或类似设备、/proc/partitions 也没有它：就是控制器/模块问题。如果能看到 SSD 和分区，但 blkid 里 UUID 对不上：才是 fstab/grub 配置问题。

经过检查，在 dmesg 中发现：

```shell
(initramfs) dmesg | grep -Ei 'nvme|vmd|ahci'
...
ahci ...: version 3.0
ahci ...: Found 1 remapped NVMe devices.
ahci ...: Switch your BIOS from RAID to AHCI mode to use them.
ahci ...: controller can't do SNTF, turning off CAP_SNTF
ahci ...: AHCI vers 0001.0301, 32 command slots, 6Gbps, RAID mode
...
```

这里说明 BIOS 里把 SATA 模式设置成了 RAID 模式，导致 Linux 内核无法识别 NVMe 设备。将 BIOS 设置（Dell 在 System Configuration -> SATA Operation 中）改为 AHCI 模式后问题解决，系统盘可以正常识别并启动。

??? llm "来自 GPT 5.2 的建议"
    建议做最小化检查，确保以后重启也稳：

    1. 确认根分区确实按 UUID 挂载（不依赖盘符）

        ```shell
        findmnt /
        cat /etc/fstab | grep -v '^\s*#' | sed '/^\s*$/d'
        blkid | grep -E 'UUID=|PARTUUID='
        ```

        - findmnt / 应该显示类似 SOURCE=UUID=...（或 /dev/nvme... 也行，但 UUID 更稳）
        - /etc/fstab 里根分区或 /boot 或 /boot/efi（如有）建议用 UUID=

    2. 更新一次 initramfs 和 grub（可选但推荐）

        ```shell
        sudo update-initramfs -u -k all
        sudo update-grub
        ```

        - 这能把你当前硬件/模块状态固化下来，避免下次内核更新后出现早期启动缺模块的意外。

### 机器重新启动后 BIOS 找不到启动项

断电重启后会显示 No bootable device found，无法进入系统，需要手动进入 BIOS 后手动添加 UEFI 启动项路径为 EFI/debian/grubx64.efi 后才能进入 grub 启动菜单，但修改后断电再重启又会丢失这个启动项。

可以重装 grub 重建一下启动项：

```shell
sudo apt update
sudo apt install --reinstall grub-efi-amd64 shim-signed efibootmgr
sudo grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=debian --recheck
sudo update-grub
sudo efibootmgr -v # 检查启动项是否存在
```

!!! llm "来自 GPT 5.2"
    你这个现象（断电后提示 No bootable device found，进 BIOS 里 UEFI 启动项会丢失，需要手动重新添加指向 \EFI\debian\grubx64.efi）通常有两类原因：

    1. UEFI NVRAM 启动项不持久（断电后丢 Boot#### 条目）：常见于 BIOS Bug、BIOS 设置未保存、或者主板/笔记本的 RTC/CMOS 供电异常（时间也会一起重置）。
    2. 缺少 UEFI “fallback” 启动路径 \EFI\BOOT\BOOTX64.EFI：就算 NVRAM 条目丢了，固件仍可走兜底路径启动。

所以推荐再拷贝一份 grub 配置到默认路径 EFI/BOOT/BOOTX64.EFI：

```shell
sudo mkdir -p /boot/efi/EFI/BOOT
sudo cp -f /boot/efi/EFI/debian/grubx64.efi /boot/efi/EFI/BOOT/BOOTX64.EFI
# 如果启用了 Secure Boot，可以拷贝 shimx64.efi
sudo cp -f /boot/efi/EFI/debian/shimx64.efi /boot/efi/EFI/BOOT/BOOTX64.EFI
```

然后重启进入 BIOS 就可以看到新的名为 debian 的启动项了，之后重启一切正常。
