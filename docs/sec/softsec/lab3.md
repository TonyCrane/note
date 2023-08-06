---
counter: True
comment: True
---

# 动/静态分析

!!! abstract
    软件安全 lab3 实验报告（2023.06.10 ~ 2023.07.02）

    !!! warning "仅供学习参考，请勿抄袭"

## 实验内容
- A（动态分析）：Fuzzing libxml2
    - 搭建 AFL++ 环境，插桩编译 libxml2 (v2.9.4) 源码（30分）
    - 使用 AFL++ 对 libxml2 进行 fuzzing，触发 crash（40分）
    - 复现 crash，结合 sanitizer 信息，理解程序为何 crash，并尝试修复（30分）
- ~~B（静态分析）：CodeQL 101~~（此部分实验已删除）
    - 完成 CodeQL 环境搭建，完成类示例中的数据库建立和 query（40分）
    - 编写预期的检测代码，并成功检测到 lab-01 中 demo.c 和 echo.c 中的 fsb 漏洞（30分）
    - 阅读学习已有的 fsb 检测代码，给出对该代码的分析以及与第2步中代码的比较（30分）

## 动态分析 (A): Fuzzing libxml2

### 环境搭建与插桩编译
根据实验指导进行 AFL++ 的编译安装：

- 安装依赖：
    - 安装系统依赖：
        ```shell
        sudo apt install -y build-essential python3-dev flex bison libglib2.0-dev libpixman-1-dev python3-setuptools
        ```
    - 安装 llvm-13 clang-13 并设置 llvm-config
        ```shell
        sudo apt install -y llvm-13 clang-13 llvm-13-dev
        sudo update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-13 13
        ```
    - 测试 llvm-config
        ```shell
        llvm-config --version
        # 输出 13.0.1
        ```
- 下载 AFL++ 源码
    ```shell
    git clone https://github.com/AFLplusplus/AFLplusplus.git --depth 1
    ```
- 编译 AFL++
    ```shell
    cd AFLplusplus
    make afl-fuzz
    make afl-showmap
    make llvm
    ```
- 设置 PATH 环境变量
    - 在 ~/.zshrc 中添加 export PATH=/home/crane/mac/Desktop/ZJU/ssec/lab3/A/AFLplusplus:$PATH

编译过程中出现了一个问题，在 make llvm 时，出现了报错 fatal error: 'list' file not found，即 #include <list\> 时没有找到 list。但后续仍可以正常生成 afl-clang-fast 等。但在编译 libxml 时 configure 检测会报错，无法利用 afl-clang-fast 编译，查看详细信息是因为找不到 SanitizerCoveragePCGUARD.<aaa>so 文件，再查看报错信息，afl-llvm-common.o 无法编译，对应 Makefile 里会导致依赖于此的 SanitizerCoveragePCGUARD.<aaa>so 也无法编译。

加上 -v 编译一个只有 #include <list\> 的源码查看详细信息，看到 Selected GCC installation: /usr/lib/gcc/x86_64-linux-gnu/12，所以需要安装对应版本的 libstdc++-dev，即 libstdc++-12-dev。sudo apt install libstdc++-12-dev 后再 make llvm 即可解决。

接下来插桩编译 libxml2 没有什么问题，直接按照文档即可：

```shell
wget http://xmlsoft.org/download/libxml2-2.9.4.tar.gz
tar -xf libxml2-2.9.4.tar.gz
cd libxml2-2.9.4
sudo apt install automake
CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --with-debug --disable-shared -without-ftp --without-http --without-legacy --without-python
AFL_USE_ASAN=1 make -j `nproc`
```

编译后 nm xmllint | grep __asan_report_error 也可以看到相应符号，说明插桩成功。

### Fuzzing
按照文档来即可：

```shell
mkdir work
cd work
wget https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/dictionaries/xml.dict
git clone https://gitee.com/ret2happy/libxml2_sample.git corpus
sudo bash -c "echo core >/proc/sys/kernel/core_pattern"
afl-fuzz -M master -m none -x xml.dict -i corpus -o output -- ../libxml2-2.9.4/xmllint --valid @@

# in another terminal
afl-fuzz -S slave1 -D -m none -x xml.dict -i corpus -o output -- ../libxml2-2.9.4/xmllint --valid @@
```

Fuzz 半小时的结果：

![](/assets/images/sec/software/lab3/fuzz.png)

可以发现出现了四次 crash，记录了其中的两次。

### Crash 复现与修复
#### Crash 复现
使用两次的 testcase 均能成功复现：

![](/assets/images/sec/software/lab3/crash0.png)
![](/assets/images/sec/software/lab3/crash1.png)

虽然报错栈有略微不同，但原因都是因为 xmlSnprintfElementContent 中发生了栈溢出，都是 CVE-2017-9048 中报的第一处漏洞引起的。

对 testcase 进行一些简化，得到如下的 testcase（其中反引号扩起来的 A*8 表示有八个 A）：

```xml
<!DOCTYPE a [
    <!ELEMENT a (`A*8`:`A*4990`)>
]>
<a/>
```

可以同样复现 crash。这里的要求就是 : 和两侧字符加起来 >= 4998 个，且不能有一侧的超过 4990 个。如果是 4998 个就会在 1323 行 crash（同第一个截图，这里是在末尾添加后括号），大于 4998 的话就会在 1279 行调用的 strcat 中 crash（同第二个截图）。

#### Crash 原因分析
valid.c 中 xmlSnprintfElementContent 函数作用是打印一个 element 的内容，即将 content 写入大小为 size 的 buf 中，如果 englob 为 1 则会在前后加上括号。

```c 
void
xmlSnprintfElementContent(char *buf, int size, xmlElementContentPtr content, int englob) {
    int len;

    if (content == NULL) return;
    len = strlen(buf);
    if (size - len < 50) {
        if ((size - len > 4) && (buf[len - 1] != '.'))
            strcat(buf, " ...");
        return;
    }
    if (englob) strcat(buf, "(");
    switch (content->type) {
        case XML_ELEMENT_CONTENT_PCDATA:
            ...
        case XML_ELEMENT_CONTENT_ELEMENT:
            if (content->prefix != NULL) {
                if (size - len < xmlStrlen(content->prefix) + 10) {
                    strcat(buf, " ...");
                    return;
                }
                strcat(buf, (char *) content->prefix);
                strcat(buf, ":");
            }
            if (size - len < xmlStrlen(content->name) + 10) {
                strcat(buf, " ...");
                return;
            }
            if (content->name != NULL)
                strcat(buf, (char *) content->name);
            break;
        case XML_ELEMENT_CONTENT_SEQ:
            ...
        case XML_ELEMENT_CONTENT_OR:
            ...
    }
    if (englob)
        strcat(buf, ")");
```

这里在进行 strcat 之前会进行 size - len（即剩余空间）与写入长度 + 10 的比较，空间不足则直接填入省略号，后续不再添加任何内容。这里的 len 应该是已经添加的字符串长度，但这里 len 只在函数最开头赋值为了 strlen(buf) 即 buf 已有长度，后续并没有更新，所以即使会出现空间不足的情况也会继续填入，造成栈溢出。

分析一下具体情况，即 8 个 A : 4990 个 A。这里的调用在之前的报错栈中可以找到是 xmlSnprintfElementContent(&expr[0], 5000, cont, 1)。而 expr[0] 已经设为了 0，所以 len 为 0。首先写入一个左括号，此时 buf 已有 1 个字符，然后 size - len = 5000 >= 8 + 10，将 prefix（即 8 个 A）拼入 buf，此时有 9 个字符，再加一个冒号一共 10 个字符。

接下来 size - len = 5000 >= 4990 + 10，将 content（4990 个 A）拼入 buf，此时在拼接的时候会写入 buf[5000]（因为写入后有 5000 个字符了），所以会在 strcat(buf, (char *)content->name) 的时候发生栈溢出。

#### Crash 修复
根据前面的分析，只需要在 strcat 之后更新 len 即可，或者将 len 全部替换为 strlen(buf) 实时计算已有长度。

修改之后重新编译 libxml2，运行之前 crash 的样例：

![](/assets/images/sec/software/lab3/fix.png)

可以发现这里 expecting 后面成功发现剩余空间不足，在冒号后面直接填入了省略号，没有发生栈溢出。
