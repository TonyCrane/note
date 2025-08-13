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
- [网路基础配置](../network/basic.md)：利用 nmtui 来配置内网静态 ip，利用 ethtool 修改网卡速率
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