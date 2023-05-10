---
comment: True
counter: True
---

# macOS TroubleShooting

!!! abstract
    在 macOS 上遇到过的一些问题和解决方法

## 有关软件
### 软件无法打开
!!! warning 
    这部分可能有些乱套，因为是回忆出来的
    
- 无法认证开发者
    - 直接通过访达右键打开软件，第二次就可以强制打开，后续都可以正常打开
    - 强制签名 `codesign --sign - --force --deep /Applications/<app>.app`
- 已损坏
    - 对于包含破解的软件等，可能会出现已损坏的情况，这时可以通过清除软件隔离属性来解决 `sudo xattr -r -d com.apple.quarantine /Applications/<app>.app`
- 无法打开软件
    - 从网上直接下载的 .app 可能直接双击或者右键都打不开，命令行 open 的话显示以下信息
        ```text
        The application cannot be opened for an unexpected reason, error=Error Domain=RBSRequestErrorDomain Code=5 "Launch failed." UserInfo={NSLocalizedFailureReason=Launch failed., NSUnderlyingError=0x600000f6d470 {Error Domain=NSPOSIXErrorDomain Code=111 "Unknown error: 111" UserInfo={NSLocalizedDescription=Launchd job spawn failed}}}
        ```
    - 原因可能是 .app 的权限设置不正确（例如多了写权限等），`sudo chmod -R 755 /Applications/<app>.app` 即可解决

### gcc-12 找不到 _stdio.h
macOS 中的 gcc 命令实际上是 clang 的 alias，使用 gcc 的话要通过 gcc-12 命令。在 macOS 或 XCode 更新后使用 gcc-12 编译可能会出现以下报错：
```text
/usr/local/Cellar/gcc/12.2.0/lib/gcc/current/gcc/x86_64-apple-darwin21/12/include-fixed/stdio.h:78:10: fatal error: _stdio.h: No such file or directory
   78 | #include <_stdio.h>
      |          ^~~~~~~~~~
compilation terminated.
```
这时需要重新安装一下 XCode 命令行工具包：`#!shell xcode-select --install`。

!!! note
    这个 Command Line Developer Tools 在安装的时候预计时间估计是不准的，刚开始的时候预计 200+ 小时完成是正常的。

## 有关网络
### 终端主机名显示为 192
参考：https://www.jianshu.com/p/8febc2993687

当路由器的 DNS 使用默认的 192.168.1.1 或 192.168.0.1 的时候计算机名会变成 192，当路由器的 DNS 使用自定义的的时候计算机名才会变成设置的名字。

可以在当前连接 wifi 设置的 DNS 一项将新增一个 8.8.8.8 即可解决。

## 有关磁盘
### 移动硬盘异常退出无法再次挂载
大概就是移动硬盘突然断连，然后重新插入的时候看不到磁盘。在系统磁盘工具里可以看到一块未装载的磁盘（`diskutil list` 也可以看到），但是无法挂载（com.apple.DiskManagement.disenter 错误 0）。

解决方案来自 https://www.xiaocrab.net/post/macos-exfat-diskmanagementdisenter-error-0/

首先 `ps aux | grep fsck`，检查是否有 fsck 程序，这是对磁盘进行检查修复的程序，可能是这里卡住了。然后 `sudo pkill -f fsck` 中断进程。接着会弹出 “macOS 无法修复磁盘” 的警告，这时硬盘可以装载上，不过是只读的。

下一步是在 mac 上正常弹出这个磁盘，然后插到 Windows 上，资源管理器打开磁盘，右键，选择 “属性”，然后选择 “工具” 选项卡，点击 “检查”，然后点击 “修复”，等待修复完成。然后再插回 mac 上，就可以正常挂载读写了。