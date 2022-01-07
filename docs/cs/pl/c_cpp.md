# C/C++

!!! abstract 
    记录一些第一次见过的用法、有用的文章/工具，以及容易忘的知识点

### 考试易错题

- [zjj大佬整理的程算易错题](https://curl.blog.luogu.org/pta-c-yu-yan-li-lun-ti-zheng-li-20209-20211-post)

### 输出类型

别的语言（比如 Python、Haskell）都可以通过内置的方法轻松得到一个变量的类型，但是 C/C++ 的话从来没了解过（C 到目前也没了解过内置的有这种功能的库）

查到了 C++ 可以使用 typeid(...).name() 的方法（在头文件 <typeinfo\> 中）得到一个变量的类型，但是结果比较抽象

C++ 还可以使用头文件 <cxxabi.h\> 这个库里提供的 abi::__cxa_demangle 函数来得到类型的字符串，比如：
```cpp
#include <stdio.h>
#include <cxxabi.h>
#include <typeinfo>

int main() {
    int *(*p)[10];
    char* str = abi::__cxa_demangle(typeid(p).name(), NULL, NULL, NULL);
    printf("%s\n", str); // 得到 int* (*) [10]
    return 0;
}
```

又搜索到了 https://cdecl.org/ 这个网站。强的很，直接输入类型声明就可以转换得到英文描述，也可以给英文描述转换成类型声明

源码：[:material-github: ridiculousfish/cdecl-blocks](https://github.com/ridiculousfish/cdecl-blocks)