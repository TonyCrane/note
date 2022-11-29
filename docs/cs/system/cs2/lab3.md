---
counter: True
comment: True
---

# GDB+QEMU 调试 64 位 RISC-V LINUX

!!! abstract
    计算机系统 Ⅱ lab3 实验报告（2022.10.27 ~ 2022.11.10）

    !!! warning
        仅供学习参考，请勿抄袭

## 实验内容
- 搭建实验环境
    - 安装 risc-v 工具链和 qemu 模拟器
- 获取 Linux 源码和已经编译好的文件系统
    - 从 kernel.org 下载最新的 Linux 源码
    - 从课程仓库克隆文件系统镜像
- 编译 Linux 内核
- 使用 QEMU 运行内核
- 使用 GDB 对内核进行调试
- 思考题
    - 使用 riscv64-linux-gnu-gcc 编译单个 .c 文件
    - 使用 riscv64-linux-gnu-objdump 反汇编前面得到的编译产物
    - 调试 Linux 时：
        1. 在 GDB 中查看汇编代码
        1. 在 0x80000000 处下断点
        1. 查看所有已下的断点
        1. 在 0x80200000 处下断点
        1. 清除 0x80000000 处的断点
        1. 继续运行直到触发 0x80200000 处的断点
        1. 单步调试一次
        1. 退出 QEMU
    - 学习 Makefile 的基本使用
        1. 观察可用的 target，应该使用 make ? 来清除 Linux 的构建产物？
        1. 默认情况下，内核编译显示的是简略信息（例如：CC init/main.o），应该使用 make ? 来显示 Linux 详细的编译过程呢？

## 环境搭建
### 安装 risc-v 工具链和 qemu 模拟器
命令行运行：
```shell
sudo apt install qemu-system-misc gcc-riscv64-linux-gnu gdb-multiarch
```
检查版本：
![](/assets/images/cs/system/cs2/lab3/img1.png)

### 安装其它后续需要的软件包
Ubuntu 不自带 make、gcc 等工具，需要手动安装：
```shell
sudo apt install build-essential
```

在后面编译内核的过程中会出现 /bin/sh: 1: flex: not found 以及 bison: not found 的错误，需要安装 flex 和 bison：
```shell
sudo apt install flex bison
```

## 获取、编译源码
### 获取 Linux 源码
在 kernel.org 上查找源码，选择 6.0.5 版本下载（6.1 版本中含有 rust，不选）并解压：
```shell
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.0.5.tar.xz
tar -xf linux-6.0.5.tar.xz
```

克隆课程仓库：
```shell
git clone https://git.zju.edu.cn/zju-sys/sys2lab-22fall-stu.git
```

### 编译 Linux 内核
进入解压后的 Linux 源码文件夹，进行编译：
```shell
make ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- defconfig
make ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- -j4
```
十分钟后完成编译，并可以 ls 查看到编译产物：
![](/assets/images/cs/system/cs2/lab3/img2.png)
![](/assets/images/cs/system/cs2/lab3/img3.png)
![](/assets/images/cs/system/cs2/lab3/img4.png)

## 运行、调试内核
### 使用 QEMU 运行内核
进入 sys2lab-22fall-stu/src/lab3 目录中，运行：
```shell
qemu-system-riscv64 -nographic -machine virt \
    -kernel ~/Desktop/linux-6.0.5/arch/riscv/boot/Image \
    -device virtio-blk-device,drive=hd0 \
    -append "root=/dev/vda ro console=ttyS0" \
    -bios fw_jump.bin -drive file=rootfs.img,format=raw,id=hd0
```
使用 QEMU 模拟器来运行内核。这里要注意，kernel 是 arch/riscv/boot/Image 而不是 vmlinux，而且不能加 -S -s，否则会等待 gdb 连接再操作运行。运行起来之后就可以进入到 shell 中运行指令了：
![](/assets/images/cs/system/cs2/lab3/img5.png)

然后 exit 退出 shell，Ctrl+A、X 退出 QEMU。

### 使用 GDB 调试内核
在一个终端运行下面命令启用一个内核并等待调试：
```shell
qemu-system-riscv64 -nographic -machine virt \
    -kernel ~/Desktop/linux-6.0.5/arch/riscv/boot/Image \
    -device virtio-blk-device,drive=hd0 \
    -append "root=/dev/vda ro console=ttyS0" \
    -bios fw_jump.bin -drive file=rootfs.img,format=raw,id=hd0 \
    -S -s
```
在另一个终端启动 gdb：
```shell
gdb-multiarch vmlinux
```
连接、下断点、查看断点，继续运行：
<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab3/img6.png" width="80%" style="margin: 0 auto;">
</div>

查看汇编、查看寄存器值、单指令运行：
<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab3/img7.png" width="80%" style="margin: 0 auto;">
</div>

查看帧栈信息：
<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab3/img8.png" width="80%" style="margin: 0 auto;">
</div>

layout asm（使用 Ctrl+X、A 退出）：
<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab3/img9.png" width="80%" style="margin: 0 auto;">
</div>

## 思考题
### 编译 c 语言文件并反汇编

和系统一中的实验一样，使用 riscv64-linux-gnu-gcc 编译、-objdump 反汇编即可。源文件：
```c
#include <stdio.h>

int main() {
    int a = 1, b = 2;
    printf("%d\n", a + b);
    return 0;
}
```
先静态编译（方便运行），然后动态编译并使用 objdump 反汇编：
![](/assets/images/cs/system/cs2/lab3/img10.png)
![](/assets/images/cs/system/cs2/lab3/img11.png)

### 调试 Linux

查看汇编、在 0x80000000 下断点、查看断点、在 0x80200000 下断点、取消 0x80000000 处的断点、继续运行：
![](/assets/images/cs/system/cs2/lab3/img12.png)

单步运行、退出：
![](/assets/images/cs/system/cs2/lab3/img13.png)

### Makefile 相关

1. **观察可用的 target，应该使用 make ? 来清除 Linux 的构建产物？**

应该使用 make clean 来清除构建产物

2. 默认情况下，内核编译显示的是简略信息（例如：CC init/main.o），应该使用 make ? 来显示 Linux 详细的编译过程呢？

make help 可以看到：
```text
  make V=0|1 [targets] 0 => quiet build (default), 1 => verbose build
  make V=2   [targets] 2 => give reason for rebuild of target
```
所以应该使用 make V=1
