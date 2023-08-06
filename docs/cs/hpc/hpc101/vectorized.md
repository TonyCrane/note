---
counter: True
comment: True
---

# 向量化计算

!!! abstract
    超算小学期第五次课课程内容，第二次实验内容

    参考：

    - 超算小学期第五次课 PPT
    - [NumPy documentation](https://numpy.org/doc/stable/)
    - [NumPy Illustrated: The Visual Guide to NumPy](https://betterprogramming.pub/numpy-illustrated-the-visual-guide-to-numpy-3b1d4976de1d)
    - [Intel Intrinsics Guide](https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html)
    - [SIMD 简介 - 知乎](https://zhuanlan.zhihu.com/p/55327037)
    - [从 Eigen 向量化谈内存对齐 - 知乎](https://zhuanlan.zhihu.com/p/93824687)

## NumPy 基础

详见 [Computer Science > 编程语言 > Python > NumPy](/cs/pl/python/numpy)

## SIMD
单指令多数据流（Single Instruction Multiple Data），在硬件层面上提供了通过一条指令运行多个运算的方法

在 x86 架构下，SIMD 一半和 SSE 和 AVX 等指令集联系在一起，SSE 和 AVX 指令集中提供了大量可以单指令操作多个数据单元的指令

SIMD 直觉上可以极大地提升效率，但实际情况比较复杂，比如内存带宽使用、解码消耗等，需要具体问题具体分析，并不代表可以同时操作两个数据，加速比就是 2

### SIMD 基础
#### 发展简史
1996 年 Intel 推出了 x86 的 MMX（MultiMedia eXtension）指令集扩展，MMX 定义了 8 个 MM 寄存器，称为 MM0 到 MM7，以及对这些寄存器进行操作的指令。每个寄存器为 64 位宽，可用于以“压缩”格式保存 64 位整数或多个较小整数，然后可以将单个指令一次应用于两个 32 位整数，四个 16 位整数或八个 8 位整数

Intel 在 1999 年又推出了全面覆盖 MMX 的 SSE（Streaming SIMD Extensions，流式 SIMD 扩展）指令集，SSE 添加了 8 个新的 128 位寄存器，XMM0 到XMM7，而后来的 x86_64 扩展又在原来的基础上添加了 8 个寄存器，XMM8 到 XMM15。SSE 支持单个寄存器存储 4 个 32 位单精度浮点数，之后的 SSE2 则支持单个寄存器存储 2 个 64 位双精度浮点数，2 个 64 位整数或 4 个 32 位整数或 8 个 16 位短整形。SSE2 之后还有 SSE3，SSE4 以及 AVX，AVX2 等扩展指令集

AVX 引入了 16 个 256 位寄存器，YMM0 至 YMM15，AVX 的 256 位寄存器和 SSE 的 128 位寄存器存在着相互重叠的关系（XMM 寄存器为 YMM 寄存器的低 128位，类似 8086 中的 ax 与 al）。AVX256 支持在一个 YMM 寄存器中存储 8 个单精度浮点数或 4 个双精度浮点数

AVX512 增加了 512 位寄存器和相关操作，但是效率不高、会使处理器发热严重、以及很可能会出现负优化，所以一般不使用

Linux 可以通过 cat /proc/cpuinfo 来查看 CPU 支持的指令集，macOS 可以通过 sysctl -a | grep machdep.cpu.features 来查看

#### SIMD 使用方法
有很多种使用 SIMD 的方法，从顶层到底层依次是：

- 使用 Intel 开发的跨平台函数库（IPP，Intel Integrated Performance Primitives），里面的指令是使用 SIMD 优化过的
- 自动向量化（Auto-vectorization），由编译器将标量优化为向量操作
- 使用编译器指示符（Compiler directive），即使用 #progma simd 强制循环向量化
- 使用内置函数（Intrinsics），Intel 提供的一些指令的包装
- 直接编写汇编代码

手写 SIMD 一般使用 Intrinsics 来实现

简单情况下没有必要手写，通过 -O3 -mavx2 编译器就可以优化地很好。但如果代码结构复杂，循环难以界定边界，甚至还有分支，这种情况下就需要手写 SIMD

### SSE/AVX Intrinsics
#### 头文件
提供这些 intrinsics 的头文件可以直接通过 *?*mmintrin.h 来导入，不同指令集的头文件不同：

- `xmmintrin.h`：SSE，支持同时对 4 个 32 位单精度浮点数的操作
- `emmintrin.h`：SSE 2，支持同时对 2 个 64 位双精度浮点数的操作
- `pmmintrin.h`：SSE 3，支持对 SIMD 寄存器的水平操作（horizontal operation），如 hadd, hsub 等...
- `tmmintrin.h`：SSSE 3，增加了额外的 instructions
- `smmintrin.h`：SSE 4.1，支持点乘以及更多的整形操作
- `nmmintrin.h`：SSE 4.2，增加了额外的 instructions
- `immintrin.h`：AVX，支持同时操作 8 个单精度浮点数或 4 个双精度浮点数

而且后面的头文件包含前面所有的内容

#### 数据类型
额外数据类型以 __m*xxx*[*T*] 的形式命名：

- *xxx*：存储数据的总位数，比如 128、256
- [*T*]：存储的每个单元的类型，单精度浮点数省略，整型为 i，双精度浮点数为 d

例如存储了 4 个双精度浮点数的 256 位数据的类型为 __m256d

#### 函数
Intrinsics 提供的函数一般以 \_mm\[*xxx*\]\_*name*\_*PT* 的形式命名：

- \[*xxx*\]：操作数的位数，若为 128 则省略
- *name*：函数名称，和用处相关
- *P*：向量操作还是标量操作
    - p 表示向量操作，例如 \_mm\_add\_ps 对四个单精度浮点数同时进行加法
    - s 表示标量操作，例如 \_mm\_add\_ss 只对最低位的单精度浮点数进行加法
    - 对于整型向量操作，MMX 指令集（操作数为 64 位）使用 p、其它情况下为 ep，例：
        ```cpp
        __m64 _mm_add_pi8(__m64 a, __m64 b)
        __m128i _mm_add_epi8(__m128i a, __m128i b)
        ```
- *T*：操作数的数据类型
    - 浮点型：单精度为 s、双精度为 d
    - 整型：有符号 i*size*、无符号 u*size*，*size* 表示每个单元中整型的宽度

主要分类：

- 存/取（store/load/set）
    - load 类函数接收一个指针，读取对应位置开始的内容，返回对应数据类型的变量
        - load 要求内存对齐（下面说）
        - loadu 不要求内存对齐
        - loadr 反向读取
    - store 类函数接收一个指针表示开始存放的首地址，和一个待存储的变量，无返回值
        - store 要求内存对齐
        - storeu 不要求内存对齐
        - storer 反向存储
    - set 类函数直接接收多个待存储的普通类型数据，返回对应大类型的变量
- 算术运算：add sub mul div sqrt 加减乘除开根号，rcp 求倒数、dp 计算点乘 ……
- 比较运算：max min cmpeq cmpge cmpgt cmple ……
- 逻辑运算：and or xor、andnot 先对第一个操作数求 not 然后逐分量 and ……
- Swizzle 运算：shuffle blend movelh

完整的指令集对应 Intrinsics 函数列表以及用法用途见：[Intel Intrinsics Guide](https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html)

#### 内存对齐
一般的存取操作要求存取的内存是对齐的，比如 \_mm\_load\_ps 要求 16 位对齐（也就是说传入的地址可以被 16 整除，即地址十六进制末尾为 0）、\_mm256\_load\_ps 要求 32 位对齐（即地址十六进制末尾为 0，倒数第二位为偶）

在栈上强制进行 32 位内存对齐：

- gcc 语法：\_\_attribute\_\_ ((aligned (32))) double a[4]
- MSVC 语法：\_\_declspec(align(32)) double a[4]

这样定义的包含四个双精度浮点数数组 a 就可以直接通过 \_mm256\_load\_pd 来读取

更多关于内存对齐，见 [从 Eigen 向量化谈内存对齐 - 知乎](https://zhuanlan.zhihu.com/p/93824687)