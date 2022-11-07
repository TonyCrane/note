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
    - 对于包含破解的软件等，可能会出现已损坏的情况，这时可以通过清除软件隔离属性来解决 `codesign --sign - --force --deep /Applications/<app>.app`

## 有关磁盘
### 移动硬盘异常退出无法再次挂载
大概就是移动硬盘突然断连，然后重新插入的时候看不到磁盘。在系统磁盘工具里可以看到一块未装载的磁盘（`diskutil list` 也可以看到），但是无法挂载（com.apple.DiskManagement.disenter 错误 0）。

解决方案来自 https://www.xiaocrab.net/post/macos-exfat-diskmanagementdisenter-error-0/

首先 `ps aux | grep fsck`，检查是否有 fsck 程序，这是对磁盘进行检查修复的程序，可能是这里卡住了。然后 `sudo pkill -f fsck` 中断进程。接着会弹出 “macOS 无法修复磁盘” 的警告，这时硬盘可以装载上，不过是只读的。

下一步是在 mac 上正常弹出这个磁盘，然后插到 Windows 上，资源管理器打开磁盘，右键，选择 “属性”，然后选择 “工具” 选项卡，点击 “检查”，然后点击 “修复”，等待修复完成。然后再插回 mac 上，就可以正常挂载读写了。